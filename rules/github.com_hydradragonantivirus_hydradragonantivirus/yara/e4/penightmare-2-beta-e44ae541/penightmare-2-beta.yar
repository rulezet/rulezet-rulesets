import "pe"
rule _PENightMare_2_Beta_ {
  meta:
    description = "PENightMare 2 Beta"

  strings:
    $0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $0 at pe.entry_point
}