proc-maps
=========
[![Build Status](https://travis-ci.org/benfred/proc-maps.svg?branch=master)](https://travis-ci.org/benfred/proc-maps)
[![Windows Build status](https://ci.appveyor.com/api/projects/status/rbu08ejt9telrw9s?svg=true)](https://ci.appveyor.com/project/benfred/proc-maps)

This crate supports reading virtual memory maps from another process - and supports
Linux OSX and Windows operating systems.

Example:

``` rust
use proc_maps::{get_process_maps, MapRange};

let maps = get_process_maps(pid)?;
for map in maps {
    println!("Filename {} Address {} Size {}", map.filename(), map.start(), map.size());
}

```

This code was originally developed by [Julia Evans](https://github.com/jvns) as part of the rbspy project: https://github.com/rbspy/rbspy.

Release under the MIT License.
