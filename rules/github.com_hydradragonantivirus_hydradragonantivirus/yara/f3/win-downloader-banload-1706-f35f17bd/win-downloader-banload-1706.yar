rule Win_Downloader_Banload_1706
{
strings:
	$a0 = { a99980a6ec43271d0afb56880556eaecb430fab30675938164c9f0f2bf86197a9d515fdfac35ed38fcdfba44faff072599c9b6ec1963214119401fc4c016c6fad28c37fe4646d9121bd2b79fced7 }


condition:
	$a0
}