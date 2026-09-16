rule TTP_XOR_WriteProcessMemory_d024 {
  strings:
    $key_d024 = { 87 56 [2] b5 74 [2] b3 41 [2] 9d 41 [2] a2 5d }

  condition:
    any of them
}