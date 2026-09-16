rule DebuggerPattern__RDTSC: AntiDebug DebuggerPattern {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = { 0F 31 }

  condition:
    any of them
}