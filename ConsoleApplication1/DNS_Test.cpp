#include <afxwin.h>

#include <iostream>
#include <io.h>
#include <fcntl.h>

#include <string>
#include <list>

#include <ws2tcpip.h>

#pragma comment(lib, "normaliz.lib")
#pragma comment(lib, "dnsapi.lib")

bool domain_name_to_internet_common_name(CStringW domain_name, std::list<CStringW>& local_internet_name, CStringW& error_message)
{
	const size_t CONST_MESSAGE_LENGTH = 500;

	wchar_t local_domain_name_unicode[CONST_MESSAGE_LENGTH];

	ZeroMemory(local_domain_name_unicode, sizeof(wchar_t) * CONST_MESSAGE_LENGTH);

	if (IdnToAscii(0, domain_name, domain_name.GetLength(), local_domain_name_unicode, CONST_MESSAGE_LENGTH) == 0)
	{
		const int local_error_message_size = 500;
		wchar_t local_error_message[local_error_message_size];

		const int local_system_error_message_size = local_error_message_size - 250;
		wchar_t local_system_error_message[local_system_error_message_size];

		wcscpy_s(local_system_error_message, local_system_error_message_size, L"IdnToAscii finished with error");

		CString local_time_string = CTime::GetCurrentTime().FormatGmt("%d/%m/%y %H:%M:%S GMT");

		wsprintf((wchar_t*)local_error_message, L"Networking error -- %s -- %s\r\n", local_system_error_message, local_time_string.GetBuffer());

		error_message.SetString(local_error_message);

		return false;
	}


	PDNS_RECORD   ppQueryResults;

	ZeroMemory(&ppQueryResults, sizeof(ppQueryResults));

	if (DnsQuery_W(local_domain_name_unicode, DNS_TYPE_CNAME, 0, NULL, &ppQueryResults, NULL) == ERROR_SUCCESS)
	{
		for (PDNS_RECORD ptr = ppQueryResults; ptr != NULL; ptr = ptr->pNext)
		{
			if (ptr->wType == DNS_TYPE_CNAME)
			{
				if (ptr->wDataLength != 0)
				{
					local_internet_name.push_back(ptr->Data.Cname.pNameHost);
				}
			}
		}

		DnsFree(ppQueryResults, DnsFreeRecordList);

		if (local_internet_name.size() != 0)
		{
			return true;
		}
		else
		{
			return false;
		}

		return true;
	}

	return false;
}


bool domain_name_to_internet_6_name(CStringW domain_name, std::list<CStringA>& local_internet_name, CStringW& error_message)
{
	const size_t CONST_MESSAGE_LENGTH = 500;

	wchar_t local_domain_name_unicode[CONST_MESSAGE_LENGTH];

	ZeroMemory(local_domain_name_unicode, sizeof(wchar_t) * CONST_MESSAGE_LENGTH);

	if (IdnToAscii(0, domain_name, domain_name.GetLength(), local_domain_name_unicode, CONST_MESSAGE_LENGTH) == 0)
	{
		const int local_error_message_size = 500;
		wchar_t local_error_message[local_error_message_size];

		const int local_system_error_message_size = local_error_message_size - 250;
		wchar_t local_system_error_message[local_system_error_message_size];

		wcscpy_s(local_system_error_message, local_system_error_message_size, L"IdnToAscii finished with error");

		CString local_time_string = CTime::GetCurrentTime().FormatGmt("%d/%m/%y %H:%M:%S GMT");

		wsprintf((wchar_t*)local_error_message, L"Networking error -- %s -- %s\r\n", local_system_error_message, local_time_string.GetBuffer());

		error_message.SetString(local_error_message);

		return false;
	}


	PDNS_RECORD   ppQueryResults;

	ZeroMemory(&ppQueryResults, sizeof(ppQueryResults));

	if (DnsQuery_W(local_domain_name_unicode, DNS_TYPE_AAAA, 0, NULL, &ppQueryResults, NULL) == ERROR_SUCCESS)
	{
		for (PDNS_RECORD ptr = ppQueryResults; ptr != NULL; ptr = ptr->pNext)
		{
			if (ptr->wType == DNS_TYPE_AAAA)
			{
				if (ptr->wDataLength != 0)
				{
					char local_address_buffer[100];
					inet_ntop(AF_INET6, &ptr->Data.AAAA.Ip6Address.IP6Byte, local_address_buffer, 100);

					local_internet_name.push_back(local_address_buffer);
				}
			}
		}

		DnsFree(ppQueryResults, DnsFreeRecordList);

		if (local_internet_name.size() != 0)
		{
			return true;
		}
		else
		{
			return false;
		}

		return true;
	}

	return false;
}

bool domain_name_to_internet_4_name(CStringW domain_name, std::list<CStringA>& local_internet_name, CStringW &error_message)
{
	const size_t CONST_MESSAGE_LENGTH = 500;

	wchar_t local_domain_name_unicode[CONST_MESSAGE_LENGTH];

	ZeroMemory(local_domain_name_unicode, sizeof(wchar_t) * CONST_MESSAGE_LENGTH);

	if (IdnToAscii(0, domain_name, domain_name.GetLength(), local_domain_name_unicode, CONST_MESSAGE_LENGTH) == 0)
	{
		const int local_error_message_size = 500;
		wchar_t local_error_message[local_error_message_size];

		const int local_system_error_message_size = local_error_message_size - 250;
		wchar_t local_system_error_message[local_system_error_message_size];

		wcscpy_s(local_system_error_message, local_system_error_message_size, L"IdnToAscii finished with error");

		CString local_time_string = CTime::GetCurrentTime().FormatGmt("%d/%m/%y %H:%M:%S GMT");

		wsprintf((wchar_t*)local_error_message, L"Networking error -- %s -- %s\r\n", local_system_error_message, local_time_string.GetBuffer());

		error_message.SetString(local_error_message);

		return false;
	}

	PDNS_RECORD   ppQueryResults;

	ZeroMemory(&ppQueryResults, sizeof(ppQueryResults));

	if (DnsQuery_W(local_domain_name_unicode, DNS_TYPE_A, 0, NULL, &ppQueryResults, NULL) == ERROR_SUCCESS)
	{
		for (PDNS_RECORD ptr = ppQueryResults; ptr != NULL; ptr = ptr->pNext)
		{
			if (ptr->wType == DNS_TYPE_A)
			{
				if (ptr->wDataLength != 0)
				{
					char local_address_buffer[100];
					inet_ntop(AF_INET, &ptr->Data.A.IpAddress, local_address_buffer, 100);

					local_internet_name.push_back(local_address_buffer);
				}
			}
		}

		DnsFree(ppQueryResults, DnsFreeRecordList);

		if (local_internet_name.size() != 0)
		{
			return true;
		}
		else
		{
			return false;
		}

		return true;
	}

	return false;
}

int main()
{
	_setmode(_fileno(stdout), _O_U16TEXT);
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stderr), _O_U16TEXT);

	for(LONGLONG counter = 0; ; counter++)
	{
		const size_t domain_to_resolve_wchar_t_size = 10000;
		wchar_t domain_to_resolve_wchar_t[domain_to_resolve_wchar_t_size];
		memset(domain_to_resolve_wchar_t, 0, domain_to_resolve_wchar_t_size * sizeof(wchar_t));


		std::wcout << CStringW(L"Input domain to resolve (\"exit\" to finish): ").GetBuffer();
		std::wcin >> domain_to_resolve_wchar_t;

		CStringW wcout_message(L"Domain to resolve: ");
		CStringW domain_to_resolve(domain_to_resolve_wchar_t);

		if (domain_to_resolve == CString(L"exit"))
		{
			break;
		}
				

		std::wcout << wcout_message.GetBuffer() << domain_to_resolve.GetBuffer() << std::endl;

		CStringW error_message_common;

		std::list<CStringW> local_internet_name_common;
		if (domain_name_to_internet_common_name(domain_to_resolve, local_internet_name_common, error_message_common))
		{
			for (auto i = local_internet_name_common.begin(); i != local_internet_name_common.end(); i++)
			{
				std::wcout << CStringW(*i).GetBuffer() << std::endl;
			}
		}
		else
		{
			std::wcout << error_message_common.GetBuffer() << std::endl;
		}

		if (local_internet_name_common.size() == 0)
		{
			std::wcout << CStringW(L"No common records found.").GetBuffer() << std::endl;
		}


		CStringW error_message_6;

		std::list<CStringA> local_internet_name_6;
		if (domain_name_to_internet_6_name(domain_to_resolve, local_internet_name_6, error_message_6))
		{
			for (auto i = local_internet_name_6.begin(); i != local_internet_name_6.end(); i++)
			{
				std::wcout << CStringW(*i).GetBuffer() << std::endl;
			}
		}
		else
		{
			std::wcout << error_message_6.GetBuffer() << std::endl;
		}

		if (local_internet_name_6.size() == 0)
		{
			std::wcout << CStringW(L"No ipv6 records found.").GetBuffer() << std::endl;
		}

		CStringW error_message_4;

		std::list<CStringA> local_internet_name_4;
		if (domain_name_to_internet_4_name(domain_to_resolve, local_internet_name_4, error_message_4))
		{
			for (auto i = local_internet_name_4.begin(); i != local_internet_name_4.end(); i++)
			{
				std::wcout << CStringW(*i).GetBuffer() << std::endl;
			}
		}
		else
		{
			std::wcout << error_message_4.GetBuffer() << std::endl;
		}

		if (local_internet_name_4.size() == 0)
		{
			std::wcout << CStringW(L"No ipv4 records found.").GetBuffer() << std::endl;
		}

		std::wcout << std::endl;

		/*/
		Sleep(1000);

		bool key_pressed = false;

		if ((GetKeyState(VK_ESCAPE) & 0x8000) != 0 && (GetKeyState(VK_LSHIFT) & 0x8000) != 0)
		{
			key_pressed = true;			
		}

		if (key_pressed)
		{
			break;
		}
		/*/
	}
}

