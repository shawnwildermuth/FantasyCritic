import BasicMixin from '@/mixins/basicMixin';

let leagueMixin = {
  mixins: [BasicMixin],
  computed: {
    leagueErrorInfo() {
      return this.$store.getters.errorInfo;
    },
    forbidden() {
      return this.$store.getters.forbidden;
    },
    inviteCode() {
      return this.$store.getters.inviteCode;
    },
    league() {
      if (!this.$store.getters.leagueYear) {
        return;
      }
      return this.$store.getters.leagueYear.league;
    },
    leagueYear() {
      return this.$store.getters.leagueYear;
    },
    userPublisher() {
      return this.$store.getters.userPublisher;
    },
    currentBids() {
      return this.$store.getters.currentBids;
    },
    currentDrops() {
      return this.$store.getters.currentDrops;
    },
    gameNews() {
      return this.$store.getters.gameNews;
    },
    publishers() {
      return this.leagueYear.publishers;
    },
    players() {
      return this.leagueYear.players;
    },
    nextPublisherUp() {
      if (!this.leagueYear || !this.leagueYear.publishers) {
        return null;
      }
      let next = _.find(this.leagueYear.publishers, ['nextToDraft', true]);
      return next;
    },
    userIsNextInDraft() {
      if (this.nextPublisherUp && this.leagueYear && this.userPublisher) {
        return this.nextPublisherUp.publisherID === this.userPublisher.publisherID;
      }

      return false;
    },
    draftIsPaused() {
      return this.leagueYear.playStatus.draftIsPaused;
    },
    isManager() {
      return this.league && this.league.isManager;
    },
    advancedProjections() {
      return this.$store.getters.advancedProjections;
    },
    draftOrderView() {
      return this.$store.getters.draftOrderView;
    }
  },
  methods: {
    notifyAction(message) {
      this.$store.dispatch('refreshLeagueYear').then(() => {
        if (message) {
          this.makeToast(message);
        }
      });
    }
  }
};

export default leagueMixin;