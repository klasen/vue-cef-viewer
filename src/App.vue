<template>
  <div id="app">
    <h1>Common Event Format (CEF) Viewer using Vue.js</h1>
    <p>
      This is a small <a href="https://vuejs.org/">Vue.js</a> App to display
      <a
        href="https://community.microfocus.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Implementation-Standard/ta-p/1645557">CEF</a>
      messages in a nice format. All parsing is done in JavaScript on the
      client side. No CEF data is sent to the server.
      <br />
      If you encounter problems or have a comment, please create an issue in
      the
      <a href="https://github.com/klasen/vue-cef-viewer">GitHub project</a>.
    </p>
    <textarea ref="message" v-model="message" placeholder="paste CEF message here" id="message"></textarea>

    <CEF :message="message" v-if="message" />
  </div>
</template>

<script>
import CEF from './components/CEF.vue'

export default {
  name: 'App',
  components: {
    CEF: CEF
  },
  data: function () {
    return {
      'message': ''
    };
  },
  mounted: function () {
    this.$nextTick(function () {
      this.$refs.message.focus();
    })
  },


}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  color: #2c3e50;
  background: #fff;
  transition: all 0.2s;
  padding: 4px;
}

textarea {
  width: 100%;
  height: 8em;
  background-color: #fcdb1f;
}


</style>
