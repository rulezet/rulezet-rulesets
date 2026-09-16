rule TTP_XOR_WriteProcessMemory_d70c {
  strings:
    $key_d70c = { 80 7e [2] b2 5c [2] b4 69 [2] 9a 69 [2] a5 75 }

  condition:
    any of them
}