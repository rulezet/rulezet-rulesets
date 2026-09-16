rule TTP_XOR_WriteProcessMemory_ec97 {
  strings:
    $key_ec97 = { bb e5 [2] 89 c7 [2] 8f f2 [2] a1 f2 [2] 9e ee }

  condition:
    any of them
}