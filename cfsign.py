#!/usr/bin/env python

# This is a partial port of the cfsign.pl from Perl to Python.
# by Michael Dales (mwd@camvine.com)
#
# The original code had the following license:
#
# Copyright 2008 Amazon Technologies, Inc.  Licensed under the Apache License, 
# Version 2.0 (the "License"); you may not use this file except in compliance 
# with the License. You may obtain a copy of the License at:
#
# http://aws.amazon.com/apache2.0
#
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR 
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import base64
from optparse import OptionParser
import os
import re
import subprocess
import sys
import time
import urllib

CANNED_POLICY = '{"Statement":[{"Resource":"%s","Condition":{"DateLessThan":{"AWS:EpochTime":%s}}}]}';


def _urlsafe_b64encode(value):
    # I've no idea who defines what's right and wrong for this, but AWS uses
    # a different policy to base64.urlsafe_b64encode
    encoded_value = base64.b64encode(value)
    return encoded_value.replace('+', '-').replace('=', '_').replace('/', '~')

def _urlsafe_b64decode(value):
    # I've no idea who defines what's right and wrong for this, but AWS uses
    # a different policy to base64.urlsafe_b64decode    
    munged_value = value.replace('-', '+').replace('_', '=').replace('~', '/')
    return base64.b64decode(munged_value)

def _rsa_sha1_sign(policy, private_key_file):
    p = subprocess.Popen(['openssl', 'sha1', '-sign', private_key_file], 
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
    p.stdin.write(policy)
    p.stdin.close()
    p.wait()
    return p.stdout.read()
    
def _create_url(path, policy, signature, key_pair_id, expires):
    # I'd just use urllib.urlencode here, but it escapes things like
    # tildas, which AWS doesn't like.
    params = {'Signature': signature, 'Key-Pair-Id': key_pair_id, 'path': path}
    if expires:
        params['Expires'] = expires        
        return '%(path)s?Expires=%(Expires)s&Signature=%(Signature)s&Key-Pair-Id=%(Key-Pair-Id)s' % params
    else:
        params['Policy'] = policy
        return '%(path)s?Policy=%(Policy)s&Signature=%(Signature)s&Key-Pair-Id=%(Key-Pair-Id)s' % params    

def encode(url, policy, expiry_epoch, key_pair_id, private_key_filename):
    
    if not policy:
        policy = CANNED_POLICY % (url, expiry_epoch)
    
    encoded_policy = _urlsafe_b64encode(policy)
    signature = _rsa_sha1_sign(policy, private_key_filename)
    encoded_signature = _urlsafe_b64encode(signature)
    
    return _create_url(url, encoded_policy, encoded_signature, key_pair_id, expiry_epoch)


if __name__ == "__main__":
    
    parser = OptionParser(usage='Usage: %prog [options] (-h for help)')
    parser.add_option('-u', '--url', dest='url')
    parser.add_option('-s', '--stream', dest='stream')
    parser.add_option('-p', '--policy', dest='policy_filename')
    parser.add_option('-a', '--action', dest='action', default='encode')
    parser.add_option('-e', '--expires', dest='expires_epoch', 
        default=int(time.time()) + 3600)
    parser.add_option('-k', '--private-key', dest='private_key_filename')
    parser.add_option('-i', '--key-pair-id', dest='key_pair_id')
    parser.add_option('-v', '--verbose', dest='verbose', default=False, action='store_false')

    options, args = parser.parse_args()
    
    if not options.url and not options.stream:
        print "Must include a stream or a URL to encode or decode with the --stream or --url option"
        sys.exit()
        
    if options.url and options.stream:
        print "Only one of --url and --stream may be specified"
        sys.exit()
        
    url = options.url or options.stream
    
    if options.action == 'encode':
        
        if not options.policy_filename:
            policy = CANNED_POLICY % (url, options.expires_epoch)            
        else:
            policy = open(options.policy_filename, 'r').read()
            options.expires_epoch = 0            
            
        generated_url = encode(url, policy, options.expires_epoch,
            options.key_pair_id, options.private_key_filename)
        
        if options.stream:
            print "Encoded stream (for use within a swf):\n%s" % generated_url
            print "Encoded and escaped stream (for use on a webpage):\n%s" % urllib.quote(generated_url)
        else:
            print "Encoded URL:\n%s" % generated_url
        
    else:
        base_url, params = urllib.splitquery(url)
        unparsed_params = params.split('&')
        params = {}
        for param in unparsed_params:
            key, value = urllib.splitvalue(param)
            params[key] = value
        
        try:
            encoded_signature = params['Signature']
        except KeyError:
            print "Missing Signature URL parameters"
            sys.exit()
        
        try:
            encoded_policy = params['Policy']
        except KeyError:
            # no policy, so make canned one
            try:
                expires = params['Expires']
            except KeyError:
                print "Either the Policy or Expires URL parameter needs to be specified"
                sys.exit()
            
            # we can't just use base_url here, as the original url may have
            # had its own params
            url_without_cf_params = url
            url_without_cf_params = re.sub('Signature=[^&]*&?', '', url_without_cf_params)
            url_without_cf_params = re.sub('Policy=[^&]*&?', '', url_without_cf_params)
            url_without_cf_params = re.sub('Expires=[^&]*&?', '', url_without_cf_params)
            url_without_cf_params = re.sub('Key-Pair-Id=[^&]*&?', '', url_without_cf_params)
                        
            policy = CANNED_POLICY % (url_without_cf_params, expires)
            encoded_policy = _urlsafe_b64encode(policy)
            
        try:
            key = params['Key-Pair-Id']
        except KeyError:
            print "Missing Key-Pair-Id parameter"
            sys.exit()
        
        policy = _urlsafe_b64decode(encoded_policy)
        
        print "Base URL: %s" % base_url
        print "Policy: %s" % policy
        print "Key: %s" % key
            