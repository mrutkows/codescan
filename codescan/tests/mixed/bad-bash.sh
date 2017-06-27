#!/bin/bash

#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#

set +x

echo "Testing a Bash file with a \"bad\" ASF License header..."
SCRIPTDIR="$(cd $(dirname "$0")/ && pwd)"
echo "This script is in directory:" $SCRIPTDIR