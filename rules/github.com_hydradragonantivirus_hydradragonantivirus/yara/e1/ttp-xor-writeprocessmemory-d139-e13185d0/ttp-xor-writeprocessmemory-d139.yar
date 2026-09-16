rule TTP_XOR_WriteProcessMemory_d139 {
  strings:
    $key_d139 = { 86 4b [2] b4 69 [2] b2 5c [2] 9c 5c [2] a3 40 }

  condition:
    any of them
}