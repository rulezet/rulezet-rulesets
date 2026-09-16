rule TTP_XOR_WriteProcessMemory_d60c {
  strings:
    $key_d60c = { 81 7e [2] b3 5c [2] b5 69 [2] 9b 69 [2] a4 75 }

  condition:
    any of them
}