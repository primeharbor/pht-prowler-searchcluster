#!/bin/bash

# Simple wrapper script to checkout the correct version of prowler and install it

PROWLER_VERSION=$1

if [[ -z "$PROWLER_VERSION" ]] ; then
  echo "Usage: $0 <PROWLER_VERSION>"
  exit 1
fi

if [[ $PROWLER_VERSION == "master" ]] ; then
  CHECKOUT_TAG="master"
else
  CHECKOUT_TAG="tags/${PROWLER_VERSION}"
fi

git clone https://github.com/prowler-cloud/prowler.git
cd prowler ; git checkout "$CHECKOUT_TAG" ; pip install --no-cache-dir .