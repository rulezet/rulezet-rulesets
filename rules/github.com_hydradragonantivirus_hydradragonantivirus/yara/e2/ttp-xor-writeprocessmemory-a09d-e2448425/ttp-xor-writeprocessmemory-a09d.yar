rule TTP_XOR_WriteProcessMemory_a09d {
  strings:
    $key_a09d = { f7 ef [2] c5 cd [2] c3 f8 [2] ed f8 [2] d2 e4 }

  condition:
    any of them
}