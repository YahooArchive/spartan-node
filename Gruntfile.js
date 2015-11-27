/*
Copyright 2015, Yahoo Inc.
Copyrights licensed under the New BSD License.
See the accompanying LICENSE file for terms.
*/

module.exports = function(grunt) {

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    jshint: {
      files: ['*.js'],
      options: {
        scripturl: true
      }
    },
    nodeunit: {
      all: ['test/*-test.js']
    }
  });

  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-nodeunit');


  grunt.registerTask('test', ['jshint', 'nodeunit']);
  grunt.registerTask('default', ['test']);
};
