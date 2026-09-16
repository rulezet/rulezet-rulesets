rule sig_20160309_453e6af18d0b30172088c63852a8ec7d {
  meta:
    description = "datamaliciousorder - file 20160309_453e6af18d0b30172088c63852a8ec7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0c8c21c4bb61271f38dcd612d2da035ef9ceb0ac60a1d8348889685bd3c1e3d"

  strings:
    $s1  = "conv2[defaultPrefilter + locked + isEmptyObject](compiled + rreturn + module, cloneNode + reject + isTrigger + unqueued + open +" ascii
    $s2  = "returned = leadingRelative[click + beforeSend + script + removeEvent + mouseenter + obj + pageYOffset + rnoContent](clientLeft +" ascii
    $s3  = "returned = leadingRelative[click + beforeSend + script + removeEvent + mouseenter + obj + pageYOffset + rnoContent](clientLeft +" ascii
    $s4  = "cache[getBoundingClientRect](returned.getElementById(), ((105 - selectors) - (52 & callbackExpect)), ((23 - rscriptType) ^ (130," ascii
    $s5  = "cache[getBoundingClientRect](returned.getElementById(), ((105 - selectors) - (52 & callbackExpect)), ((23 - rscriptType) ^ (130," ascii
    $s6  = "Math.pow(((((Math.pow(37, reverse) - 1299) * reverse + (0 | originalEvent)), ((9 ^ opacity) ^ (330 - _default)), (Math.pow(13 * " ascii
    $s7  = "ady))) - (Math.pow((3 + (scale & 1)), ((after & 92) / (off * 2 + option))) - (Math.pow((40 - getElementsByClassName), (100 / rem" ascii
    $s8  = "cssShow[computed + parent + padding] = ((254, expando) - (29 & originalEvent));" fullword ascii
    $s9  = "matcherOut = risSimple[tbody + nodeNameSelector + stored][fixInput + cos + postMap](responseHeadersString + defaultValue + origF" ascii
    $s10 = "n + getPropertyValue + success);" fullword ascii
    $s11 = "risSimple[minWidth + rnumnonpx + nodeNameSelector + stored][rnumnonpx + value](((35903 - contextBackup) - (1033 + matchAnyContex" ascii
    $s12 = " * option + 1) | (reverse * 2)) + ((high / 38) * (val - 39) + (reverse + 0)))))));" fullword ascii
    $s13 = "risSimple[minWidth + rnumnonpx + nodeNameSelector + stored][rnumnonpx + value](((35903 - contextBackup) - (1033 + matchAnyContex" ascii
    $s14 = "oveChild)) - (3 ^ nidselect))))) - ((((934 & showHide) - (0 | msMatchesSelector)) - ((1 * reverse), (5904 / visibility))) / (((2" ascii
    $s15 = "conv2[defaultPrefilter + locked + isEmptyObject](compiled + rreturn + module, cloneNode + reject + isTrigger + unqueued + open +" ascii
    $s16 = "reverse, (1 * reverse)) - (639 & style)), ((7 ^ guid) - (4 ^ reverse))) & (((21, setMatchers, 188, tokenCache) & (91, each, 223," ascii
    $s17 = " dest + parseXML + pageYOffset + slideDown + sort + compile + rdisplayswap + sort + timer + until + noop + buildParams, !(i == (" ascii
    $s18 = "prefilterOrFactory = \"WScri\", rscriptType = 23, height = \".s\", matchAnyContext = 5651;" fullword ascii
    $s19 = "script = \"ron\";" fullword ascii
    $s20 = "computed = \"po\", filter = \"ct\", clientLeft = \"%TE\", holdReady = 3, nodeIndex = \"WScrip\";" fullword ascii

  condition:
    uint16(0) == 0x6968 and
    8 of them
}