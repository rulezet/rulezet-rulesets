rule TTP_XOR_WriteProcessMemory_d12c {
  strings:
    $key_d12c = { 86 5e [2] b4 7c [2] b2 49 [2] 9c 49 [2] a3 55 }

  condition:
    any of them
}