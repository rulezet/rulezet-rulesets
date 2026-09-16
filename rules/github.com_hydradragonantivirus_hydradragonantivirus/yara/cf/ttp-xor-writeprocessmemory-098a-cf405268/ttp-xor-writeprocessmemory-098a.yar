rule TTP_XOR_WriteProcessMemory_098a {
  strings:
    $key_098a = { 5e f8 [2] 6c da [2] 6a ef [2] 44 ef [2] 7b f3 }

  condition:
    any of them
}