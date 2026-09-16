rule TTP_XOR_WriteProcessMemory_c430 {
  strings:
    $key_c430 = { 93 42 [2] a1 60 [2] a7 55 [2] 89 55 [2] b6 49 }

  condition:
    any of them
}