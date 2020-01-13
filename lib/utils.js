'use strict';

const debug = require('debug')('rbac');
module.exports.any = any;
module.exports.isGlob = isGlob;
module.exports.globToRegex = globToRegex;

/**********************/

function any(promises) {
  if(promises.length < 1) {
    return Promise.resolve(false);
  }
  return Promise.all(
    promises.map($p =>
      $p
        .catch(err => {
          debug('Underlying promise rejected', err);
          return false;
        })
        .then(result => {
          if(result) {
            throw new Error('authorized');
          }
        })
    )
  )
    .then(() => false)
    .catch(err => err && err.message === 'authorized');
}

function isGlob(string) {
  return string.includes('*');
}

function globToRegex(string) {
  return new RegExp('^' + string.replace(/\*/g, '.*'));
}