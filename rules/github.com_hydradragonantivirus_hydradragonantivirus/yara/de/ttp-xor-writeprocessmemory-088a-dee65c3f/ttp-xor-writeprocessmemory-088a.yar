rule TTP_XOR_WriteProcessMemory_088a {
  strings:
    $key_088a = { 5f f8 [2] 6d da [2] 6b ef [2] 45 ef [2] 7a f3 }

  condition:
    any of them
}