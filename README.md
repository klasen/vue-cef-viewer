# vue-cef-viewer

Parse a raw [Common Event Format](https://community.microfocus.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Implementation-Standard/ta-p/1645557) (CEF) log message and show it in a tabular view using [Vue.js](https://vuejs.org/).

Try it online at <https://klasen.github.io/vue-cef-viewer/>.

## Project setup

```sh
npm install
```

### Scrape CEF meta-data

Scrape CEF implementation standard and save producer and consumer extension dictionaries as JSON and CSV.

```sh
node ./docs/scrape.js
```

### Compiles and hot-reloads for development

```sh
npm run serve
```

### Compiles and minifies for production

```sh
npm run build
# initial
git subtree push --prefix dist origin gh-pages
# on updates
git push origin :gh-pages && git subtree push --prefix dist origin gh-pages
```

### Lints and fixes files

```sh
npm run lint
```

### Customize configuration

See [Configuration Reference](https://cli.vuejs.org/config/).
