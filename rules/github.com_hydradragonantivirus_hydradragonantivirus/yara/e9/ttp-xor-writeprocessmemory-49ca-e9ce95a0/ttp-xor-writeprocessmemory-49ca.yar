rule TTP_XOR_WriteProcessMemory_49ca {
  strings:
    $key_49ca = { 1e b8 [2] 2c 9a [2] 2a af [2] 04 af [2] 3b b3 }

  condition:
    any of them
}