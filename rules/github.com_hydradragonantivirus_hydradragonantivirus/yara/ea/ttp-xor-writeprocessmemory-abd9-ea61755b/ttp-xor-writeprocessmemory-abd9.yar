rule TTP_XOR_WriteProcessMemory_abd9 {
  strings:
    $key_abd9 = { fc ab [2] ce 89 [2] c8 bc [2] e6 bc [2] d9 a0 }

  condition:
    any of them
}