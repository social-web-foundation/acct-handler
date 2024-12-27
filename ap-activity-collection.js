
import { ActivityPubElement } from './ap-element.js';
import { html, css } from 'https://cdn.jsdelivr.net/gh/lit/dist@3/core/lit-core.min.js';
import './ap-activity.js';

class ActivityPubActivityCollection extends ActivityPubElement {

  static get properties() {
    return {
      ...super.properties,
      _activities: { type: Array, state: true },
    }
  }

  static MAX_ACTIVITIES = 20;

  static styles = css`
  :host {
    display: block;
  }
  .activity {
      border: 1px solid lightgray;
      border-radius: 8px;
      padding: 8px;
      margin: 8px 0;
  }
  `;

  constructor() {
    super();
  }

  render() {
    return html`
      <ol class="activities">
      ${this._activities?.map(activity => html`
        <li class="activity">
        ${(typeof activity === 'string')
        ? html`<ap-activity activity-id="${activity}"></ap-activity>`
        : html`<ap-activity activity="${JSON.stringify(activity)}"></ap-activity>`}
        </li>
        `)}
      </ol>
    `;
  }

  updated(changedProperties) {
    super.updated(changedProperties);
    if (changedProperties.has('json')) {
      this.fetchActivities();
    }
  }

  async fetchActivities() {
    const activities = [];

    if (this.json.items) {
      activities.push(...this.json.items);
    } else if (this.json.orderedItems) {
      activities.push(...this.json.orderedItems);
    } else if (this.json.first) {
      let next = this.json.first;
      while (next &&
        activities.length < this.constructor.MAX_ACTIVITIES) {
        const res = await this.constructor.fetchFunction(next, {
          headers: { Accept: this.constructor.MEDIA_TYPES.join(', ') }
        });
        if (!res.ok) {
          console.error('Failed to fetch collection page', res);
          break;
        }
        const page = await res.json();
        if (page.items) {
          activities.push(...page.items);
        } else if (page.orderedItems) {
          activities.push(...page.orderedItems);
        }
        next = page.next;
      }
    }

    this._activities = activities;
  }
}

customElements.define('ap-activity-collection', ActivityPubActivityCollection);