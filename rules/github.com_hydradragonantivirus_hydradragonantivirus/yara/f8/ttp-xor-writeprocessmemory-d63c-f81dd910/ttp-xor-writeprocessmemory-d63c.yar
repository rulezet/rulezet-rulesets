rule TTP_XOR_WriteProcessMemory_d63c {
  strings:
    $key_d63c = { 81 4e [2] b3 6c [2] b5 59 [2] 9b 59 [2] a4 45 }

  condition:
    any of them
}