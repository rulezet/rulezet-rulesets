import "pe"
rule tElockv099_ren: tE {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = { E9 0D E4 FF FF }

  condition:
    $a0 at pe.entry_point
}