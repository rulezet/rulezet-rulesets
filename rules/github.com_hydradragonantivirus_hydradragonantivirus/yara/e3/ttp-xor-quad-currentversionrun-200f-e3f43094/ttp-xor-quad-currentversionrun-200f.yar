rule TTP_XOR_QUAD_CurrentVersionRun_200f {
  strings:
    $key_200f = { 73 60 [2] 57 6e [2] 7c 42 [2] 52 60 [2] 46 7b [2] 49 61 [2] 57 7c [2] 55 7d [2] 4e 7b [2] 52 7c [2] 4e 53 }

  condition:
    any of them
}