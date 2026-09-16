rule visbot {
    strings:
		$ = "stripos($buf, 'Visbot')!==false && stripos($buf, 'Pong')!==false"
		$ = "stripos($buf, 'Visbot') !== false && stripos($buf, 'Pong')"
    condition: any of them
}