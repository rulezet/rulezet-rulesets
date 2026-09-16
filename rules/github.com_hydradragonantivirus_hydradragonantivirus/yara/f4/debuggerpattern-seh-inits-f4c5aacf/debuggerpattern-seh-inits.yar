rule DebuggerPattern__SEH_Inits: AntiDebug DebuggerPattern {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = { 64 89 25 00 00 00 00 }

  condition:
    any of them
}