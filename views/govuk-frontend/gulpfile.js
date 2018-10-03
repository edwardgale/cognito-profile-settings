#!/usr/bin/env node
const nunjucks = require('nunjucks');
const gulp = require('gulp');
const sass = require('gulp-sass');

console.log('asfas');
gulp.task('hello', function() {
    console.log('Hello Zell');
});

gulp.task('styles', function() {
    gulp.src('**/*.scss')
    .pipe(sass().on('error', sass.logError))
    .pipe(gulp.dest('./css/'));
});

//Watch task
gulp.task('default',function() {
    gulp.watch('**/*.scss',['styles']);
});
