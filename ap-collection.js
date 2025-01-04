
import { ActivityPubElement } from './ap-element.js';
import { html, css } from 'https://cdn.jsdelivr.net/gh/lit/dist@3/core/lit-core.min.js';
import { ActivityPubObject } from './ap-object.js';

export class ActivityPubCollectionElement extends ActivityPubElement {

  static _itemClass = ActivityPubObject;

  static get properties() {
    return {
      ...super.properties,
      pageSize: { type: Number, attribute: 'page-size' },
      _items: { type: Array, state: true },
    }
  }

  static styles = css`
  :host {
    display: block;
  }
  `;

  constructor() {
    super();
    this.pageSize = 20;
  }

  render() {
    if (this._error) {
      return html`
      <div class="items">
        <p>${this._error}</p>
      </div>
    `;
    } else if (!this.json) {
      return html`
      <div class="items">
        <p>Loading...</p>
      </div>
    `;
    } else {
      const cls = this.constructor._itemElement;
      return html`
        <ol class="items">
        ${this._items?.map(item => {
        const el = new cls();
        if (typeof item === 'string') {
          el.objectId = item;
        } else {
          el.json = item;
        }
        return html`
          <li class="item">
          ${el}
          </li>
          `})}
        </ol>
      `;
    }
  }

  updated(changedProperties) {
    super.updated(changedProperties);
    if (changedProperties.has('json')) {
      this.fetchItems();
    }
  }

  async fetchItems() {
    const items = [];

    if (this.json.items) {
      items.push(...this.json.items);
    } else if (this.json.orderedItems) {
      items.push(...this.json.orderedItems);
    } else if (this.json.first) {
      let next = this.json.first;
      while (next &&
        items.length < this.pageSize) {
        const res = await this.constructor.fetchFunction(next, {
          headers: { Accept: this.constructor.MEDIA_TYPES.join(', ') }
        });
        if (!res.ok) {
          console.error('Failed to fetch collection page', res);
          break;
        }
        const page = await res.json();
        if (page.items) {
          items.push(...page.items);
        } else if (page.orderedItems) {
          items.push(...page.orderedItems);
        }
        next = page.next;
      }
    }

    this._items = items;
  }
}