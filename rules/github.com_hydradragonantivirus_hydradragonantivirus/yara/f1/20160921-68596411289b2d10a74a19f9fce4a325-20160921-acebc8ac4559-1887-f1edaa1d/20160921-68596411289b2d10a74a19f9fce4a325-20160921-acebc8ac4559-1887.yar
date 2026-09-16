rule _20160921_68596411289b2d10a74a19f9fce4a325_20160921_acebc8ac4559_1887 {
  meta:
    description = "datamaliciousorder - from files 20160921_68596411289b2d10a74a19f9fce4a325.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"
    hash2       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"

  strings:
    $s1  = ")(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s2  = "\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f0" ascii
    $s3  = "(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s4  = "f000(){return \"PTs\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s5  = "ion f000(){return \"ZIi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lo\";})(),(function f000(){return " ascii
    $s6  = "urn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(f" ascii
    $s7  = "0(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\"" ascii
    $s8  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq" ascii
    $s9  = "(function f000(){return \"DAp\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){r" ascii
    $s10 = "){return \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}