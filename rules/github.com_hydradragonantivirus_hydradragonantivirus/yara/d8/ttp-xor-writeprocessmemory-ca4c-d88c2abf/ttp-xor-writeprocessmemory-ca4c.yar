rule TTP_XOR_WriteProcessMemory_ca4c {
  strings:
    $key_ca4c = { 9d 3e [2] af 1c [2] a9 29 [2] 87 29 [2] b8 35 }

  condition:
    any of them
}