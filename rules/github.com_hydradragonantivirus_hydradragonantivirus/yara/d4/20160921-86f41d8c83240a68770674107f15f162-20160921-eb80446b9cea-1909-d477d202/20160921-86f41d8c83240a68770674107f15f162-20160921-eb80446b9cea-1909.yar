rule _20160921_86f41d8c83240a68770674107f15f162_20160921_eb80446b9cea_1909 {
  meta:
    description = "datamaliciousorder - from files 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash2       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"

  strings:
    $s1  = ")(),(function f000(){return \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s2  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vj" ascii
    $s3  = "n\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s4  = "\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s5  = "(){return \"EZu\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";" ascii
    $s6  = "function f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){re" ascii
    $s7  = "eturn \"SEo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s8  = "function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){re" ascii
    $s9  = "on f000(){return \"TKp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s10 = "n f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}