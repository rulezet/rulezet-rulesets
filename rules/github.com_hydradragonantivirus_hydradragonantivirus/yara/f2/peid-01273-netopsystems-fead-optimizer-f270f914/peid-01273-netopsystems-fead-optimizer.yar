rule PEiD_01273_Netopsystems_FEAD_Optimizer_ {
  meta:
    description = "[Netopsystems FEAD Optimizer]"
    ep_only     = "true"

  strings:
    $a = { 60 BE 00 50 43 00 8D BE 00 C0 FC FF }

  condition:
    $a
}