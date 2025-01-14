import moment from 'moment';
import GraphemeBreaker from 'grapheme-breaker-mjs';

export default {
  publisherIconIsValid(publisherIcon) {
    if (!publisherIcon) {
      return true;
    }
    let length = GraphemeBreaker.countBreaks(publisherIcon);
    return length === 1;
  },
  ordinal_suffix_of(i) {
    var j = i % 10,
      k = i % 100;
    if (j == 1 && k != 11) {
      return i + 'st';
    }
    if (j == 2 && k != 12) {
      return i + 'nd';
    }
    if (j == 3 && k != 13) {
      return i + 'rd';
    }
    return i + 'th';
  },
  formatPublisherGameReleaseDate(publisherGame, shorten) {
    if (!publisherGame.masterGame) {
      return 'Unknown';
    }

    return this.formatMasterGameReleaseDate(publisherGame.masterGame, shorten);
  },
  formatMasterGameReleaseDate(masterGame, shorten) {
    if (masterGame.releaseDate) {
      if (shorten) {
        return moment(masterGame.releaseDate).format('MMM Do, YYYY');
      }
      return moment(masterGame.releaseDate).format('MMMM Do, YYYY');
    }

    if (shorten) {
      return masterGame.estimatedReleaseDate;
    }

    return masterGame.estimatedReleaseDate + ' (Estimated)';
  },
  formatPublisherGameAcquiredDate(publisherGame) {
    let type = '';
    if (publisherGame.overallDraftPosition) {
      type = `Drafted ${this.ordinal_suffix_of(publisherGame.overallDraftPosition)}`;
    } else if (publisherGame.bidAmount || publisherGame.bidAmount === 0) {
      type = 'Picked up for $' + publisherGame.bidAmount;
    } else if (publisherGame.acquiredInTradeID) {
      type = 'Acquired in a trade';
    } else {
      type = 'Acquired';
    }
    let date = moment(publisherGame.timestamp).format('MMMM Do, YYYY');
    return type + ' on ' + date;
  },
  formatPublisherGameRemovedDate(publisherGame) {
    if (!publisherGame.removedTimestamp) {
      return '';
    }
    return moment(publisherGame.removedTimestamp).format('MMMM Do, YYYY');
  },
  formatLongDateTime(dateTime) {
    return moment(String(dateTime)).local().format('MMMM Do, YYYY, h:mm:ss a');
  },
  formatLongDate(date) {
    return moment(String(date)).local().format('MMMM Do, YYYY');
  },
  toISODateString(date) {
    const fullString = date.toISOString();
    const dateString = fullString.substring(0, 10);
    return dateString;
  },
  roundNumber(value, decimals) {
    if (value === 0) {
      return 0;
    }
    if (!value) {
      return '--';
    }

    if (!decimals) {
      decimals = 0;
    }

    value = Math.round(value * Math.pow(10, decimals)) / Math.pow(10, decimals);
    return value;
  }
};
