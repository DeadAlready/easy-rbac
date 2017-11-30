'use strict';

const debug = require('debug')('rbac');
module.exports.any = any;

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