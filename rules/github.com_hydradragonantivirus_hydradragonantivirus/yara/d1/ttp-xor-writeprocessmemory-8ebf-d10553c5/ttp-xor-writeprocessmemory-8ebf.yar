rule TTP_XOR_WriteProcessMemory_8ebf {
  strings:
    $key_8ebf = { d9 cd [2] eb ef [2] ed da [2] c3 da [2] fc c6 }

  condition:
    any of them
}