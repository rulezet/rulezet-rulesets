rule TTP_XOR_WriteProcessMemory_dafa {
  strings:
    $key_dafa = { 8d 88 [2] bf aa [2] b9 9f [2] 97 9f [2] a8 83 }

  condition:
    any of them
}