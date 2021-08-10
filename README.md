proc-maps
=========
[![Build Status](https://travis-ci.org/rbspy/proc-maps.svg?branch=master)](https://travis-ci.org/rbspy/proc-maps)
[![Windows Build status](https://ci.appveyor.com/api/projects/status/ga754jgewu4u1v6m?svg=true)](https://ci.appveyor.com/project/benfred/proc-maps-wugxn)
[![crates.io](https://img.shields.io/crates/v/proc-maps.svg)](https://crates.io/crates/proc-maps)
[![docs.rs](https://docs.rs/proc-maps/badge.svg)](https://docs.rs/proc-maps)

This crate supports reading virtual memory maps from another process - and supports
Linux OSX and Windows operating systems.

Example:

``` rust
use proc_maps::get_process_maps;

let maps = get_process_maps(pid)?;
for map in maps {
    println!("Filename {:?} Address {} Size {}", map.filename(), map.start(), map.size());
}

```

This code was originally developed by [Julia Evans](https://github.com/jvns) as part of the rbspy project: https://github.com/rbspy/rbspy.

Release under the MIT License.
