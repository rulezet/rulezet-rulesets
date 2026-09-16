rule TTP_XOR_WriteProcessMemory_ec1c {
  strings:
    $key_ec1c = { bb 6e [2] 89 4c [2] 8f 79 [2] a1 79 [2] 9e 65 }

  condition:
    any of them
}