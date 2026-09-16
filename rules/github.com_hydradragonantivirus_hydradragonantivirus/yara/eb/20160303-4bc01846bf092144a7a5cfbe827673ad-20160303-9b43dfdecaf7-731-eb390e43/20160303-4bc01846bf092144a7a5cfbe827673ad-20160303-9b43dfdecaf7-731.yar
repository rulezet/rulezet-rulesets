rule _20160303_4bc01846bf092144a7a5cfbe827673ad_20160303_9b43dfdecaf7_731 {
  meta:
    description = "datamaliciousorder - from files 20160303_4bc01846bf092144a7a5cfbe827673ad.js, 20160303_9b43dfdecaf74f57ec8092f57cdf29a5.js, 20160303_abcda58a8df59877b576ddba9fd1ca94.js, 20160303_cb8934e961dbdbc7cc863f2c34960c99.js, 20160303_e110b705d2b222611722bf4fdf2578df.js, 20160303_e34a0830e308504a780afb1b89f1a478.js, 20160303_e977b57cd1a9534e58a431cc23def1fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "097f424d0e368b01770b887da1bbbae4ad5bf2327a3525d3f8260528b65d8b84"
    hash2       = "244cf39d1a84cc499874b202841075cee6851a812c5e1541bf96130aec760d52"
    hash3       = "52f26d90b8ecd9f6c15ce4c022b76f00fc2385b25f18aeab67114df0388bcfbd"
    hash4       = "ab9d673541f82409136dc6e343cbcd330999e3a358444f8c4097a1ad612950ed"
    hash5       = "4497a68a43a6432b03e1f3339229d3b6303df120415e2288be42c3eb82218751"
    hash6       = "a06c96ebfc17b8948f950ffefd038e9f21e793950a347bb3c80a98227b1bea95"
    hash7       = "1c7092bffb7042e719a90ffac039878c4f8fe174fb933e7cc6de4832589c9efd"

  strings:
    $s1  = "* jshint ignore: end */" fullword ascii
    $s2  = " args, proxy, tmp;" fullword ascii
    $s3  = "        //}   Quick check to determine if target is callable, in the spec    this throws a TypeError, but we will just return un" ascii
    $s4  = "te a danger of using the global  unguarded in another place, it seems safer to just disable JSHint for these  three lines. /* js" ascii
    $s5  = "        //}   Quick check to determine if target is callable, in the spec    this throws a TypeError, but we will just return un" ascii
    $s6  = "// Populate the class2type map jQuery.each( \\\"Boolean Number String Function Array Date RegExp Object Error Symbol\\\".split( " ascii
    $s7  = "    // JSHint would error on this code due to the Symbol not being defined in ES5.  Defining this global in .jshintrc would crea" ascii
    $s8  = "        //  Bind a function to a context, optionally partially applying any   arguments.  proxy: function( fn, context ) {   var" ascii
    $s9  = "        //  Bind a function to a context, optionally partially applying any   arguments.  proxy: function( fn, context ) {   var" ascii
    $s10 = "    //  jQuery.support is not used in Core but other projects attach their   properties to it so it needs to exist.  support: su" ascii
    $s11 = "hint ignore: start */ if ( typeof Symbol === \\\"function\\\" ) {  jQuery.fn[ Symbol.iterator ] = deletedIds[ Symbol.iterator ];" ascii
    $s12 = "\" ), function( i, name ) {  class2type[ \\\"[object \\\" + name + \\\"]\\\" ] = name.toLowerCase(); } );" fullword ascii
    $s13 = "    //  jQuery.support is not used in Core but other projects attach their   properties to it so it needs to exist.  support: su" ascii
    $s14 = "// Populate the class2type map jQuery.each( \\\"Boolean Number String Function Array Date RegExp Object Error Symbol\\\".split( " ascii
    $s15 = "    //  return proxy;  }," fullword ascii
    $s16 = "        //  if ( typeof context === \\\"string\\\" ) {    tmp = fn[ context ];    context = fn;    fn = tmp;   " fullword ascii
    $s17 = "    // JSHint would error on this code due to the Symbol not being defined in ES5.  Defining this global in .jshintrc would crea" ascii
    $s18 = "        //}   Simulated bind   args = slice.call( arguments, 2 );   proxy = function() {    return fn.apply( context || this, ar" ascii
    $s19 = "        //}   Simulated bind   args = slice.call( arguments, 2 );   proxy = function() {    return fn.apply( context || this, ar" ascii

  condition:
    (uint16(0) == 0x2f2f and (8 of them)
    ) or (all of them)
}