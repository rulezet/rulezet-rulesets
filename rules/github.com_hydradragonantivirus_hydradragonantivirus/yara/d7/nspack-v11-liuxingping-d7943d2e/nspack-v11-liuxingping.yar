import "pe"
rule _nSpack_V11__LiuXingPing_ {
  meta:
    description = "nSpack V1.1 -> LiuXingPing"

  strings:
    $0 = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }
    $1 = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}