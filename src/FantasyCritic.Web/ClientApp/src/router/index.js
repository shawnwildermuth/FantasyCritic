import Vue from 'vue';
import VueRouter from 'vue-router';

import store from '../store';
import { routes } from './routes';

Vue.use(VueRouter);

let router = new VueRouter({
  mode: 'history',
  routes
});

router.beforeEach(function (toRoute, fromRoute, next) {
  if (toRoute.meta.title) {
    document.title = toRoute.meta.title + ' - Fantasy Critic';
  }

  var getPrereqs = function () {
    var prereqs = [];
    prereqs.push(
      new Promise(function (resolve) {
        if (!store.getters.allTags && !store.getters.masterGamesIsBusy) {
          store.dispatch('getAllTags').then(() => {
            resolve();
          });
        } else {
          resolve();
        }
      })
    );

    prereqs.push(
      new Promise(function (resolve) {
        if (!store.getters.bidTimes && !store.getters.bidTimesIsBusy) {
          store.dispatch('getBidTimes').then(() => {
            resolve();
          });
        } else {
          resolve();
        }
      })
    );

    return prereqs;
  };

  Promise.all(getPrereqs());

  //If we are current, we're good to go
  if (store.getters.isAuth) {
    if (toRoute.meta.publicOnly) {
      next({ path: '/home' });
      return;
    }
    next();
    return;
  }

  store
    .dispatch('getUserInfo')
    .then(() => {
      if (store.getters.isAuth) {
        if (toRoute.meta.publicOnly) {
          next({ path: '/home' });
          return;
        } else {
          next();
          return;
        }
      } else {
        if (toRoute.meta.isPublic) {
          next();
          return;
        } else {
          store.commit('clearUserInfo');
          window.location.href = '/Identity/Account/Login';
          return;
        }
      }
    })
    .catch(() => {
      console.log('Router error');
      store.commit('clearUserInfo');
      window.location.href = '/Identity/Account/Login';
      return;
    });
});

export default router;
