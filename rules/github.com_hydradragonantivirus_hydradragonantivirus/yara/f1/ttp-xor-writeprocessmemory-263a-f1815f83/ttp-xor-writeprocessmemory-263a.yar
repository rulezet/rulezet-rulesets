rule TTP_XOR_WriteProcessMemory_263a {
  strings:
    $key_263a = { 71 48 [2] 43 6a [2] 45 5f [2] 6b 5f [2] 54 43 }

  condition:
    any of them
}