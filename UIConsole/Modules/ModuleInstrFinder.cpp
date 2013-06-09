/*
Copyright (C) 2013 George Nicolaou <george[at]preaver.[dot]com>

This file is part of Exploitation Toolkit Icarus (ETI) UI Console.

Exploitation Toolkit Icarus (ETI) UI Console is free software: you can redistribute
it and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

Exploitation Toolkit Icarus (ETI) UI Console is distributed in the hope that it
will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Exploitation Toolkit Icarus (ETI) UI Console.
If not, see <http://www.gnu.org/licenses/>.
*/


#include "ModuleInstrFinder.h"
#include "IMemory.h"
#include "MemoryPage.h"
#include "ImageHeaderMemory.h"
#include "InstructionFinder.h"
#include "IProtections.h"
#include "HexPattern.h"

void ExecuteInstrFinder( PMODULEARGS lpModuleArgs );

/*
typedef struct _moduleargs {
char lpArgumentCommand;
char * lpArgumentDescription;
ENUM_TYPE eVariableType;
BOOL bSet;
BOOL bRequired;
void * lpArgument;
} MODULEARGS, * PMODULEARGS;
*/

void * lpPatternInstrFinderArgs[3];

MODULEARGS lpsModuleInstrFinderArgs[] = {
	{
		"p",
		"Process ID of the process to scan",
		TYPE_INT,
		FALSE,
		TRUE,
		&lpPatternInstrFinderArgs[0]
	},
	{
		"i",
		"Instruction bytes to look for",
		TYPE_STRING,
		FALSE,
		TRUE,
		&lpPatternInstrFinderArgs[1]
	},
	{
		"f0",
		"Filter out modules with DEP",
		TYPE_FLAG,
		FALSE,
		FALSE
	},
	{
		"f1",
		"Filter out modules with GS",
		TYPE_FLAG,
		FALSE,
		FALSE
	},
	{
		"f2",
		"Filter out modules with SEH",
		TYPE_FLAG,
		FALSE,
		FALSE
	},
	{
		"f3",
		"Filter out modules with ASLR",
		TYPE_FLAG,
		FALSE,
		FALSE
	},
};

MODULE sModuleInstrFinder = {
	"Instruction Finder",
	"Search for an instruction within the loaded modules of a process.",
	"instruction_finder",
	"if",
	6,
	(PMODULEARGS)&lpsModuleInstrFinderArgs,
	&ExecuteInstrFinder
};

void ExecuteInstrFinder( PMODULEARGS lpModuleArgs )
{
	int nProcessId = (int)lpModuleArgs->lpArgument;
	char * lpInstruction = (char *)(lpModuleArgs+1)->lpArgument;
	BOOL bProtection0 = FALSE, bProtection1 = FALSE, bProtection2 = FALSE,
		bProtection3 = FALSE;
	BOOL bFilterEnabled = FALSE;

	IProtections::_PROTECTION_FILTER eProtectionFilter = 
		(IProtections::_PROTECTION_FILTER)NULL;

	if( (BOOL)(lpModuleArgs+2)->bSet ) 
		eProtectionFilter = (IProtections::_PROTECTION_FILTER)
			( eProtectionFilter | IProtections::PROTECTION_0 );

	if( (BOOL)(lpModuleArgs+3)->bSet )
		eProtectionFilter = (IProtections::_PROTECTION_FILTER)
			( eProtectionFilter | IProtections::PROTECTION_1 );

	if( (BOOL)(lpModuleArgs+4)->bSet )
		eProtectionFilter = (IProtections::_PROTECTION_FILTER)
			( eProtectionFilter | IProtections::PROTECTION_2 );

	if( (BOOL)(lpModuleArgs+5)->bSet )
		eProtectionFilter = (IProtections::_PROTECTION_FILTER)
			( eProtectionFilter | IProtections::PROTECTION_ASLR );

	IProtections * lpcProtections = IProtections::init_get_instance();
	lpcProtections->apply_protection_filter( eProtectionFilter );

	
	HexPattern cHexPattern;
	cHexPattern.parse_pattern( lpInstruction );

	vector<Address *> vlpcAddresses;
	InstructionFinder cInstructionFinder;
	if( cInstructionFinder.find_instruction_in_exe( nProcessId, lpcProtections, 
		&cHexPattern, &vlpcAddresses ) == FALSE ) {
			dprintflvl( 1, "Error finding Instruction" );
			return;
	}

	if( vlpcAddresses.size() == 0 ) {
		printf("Instruction not found\n");
		return;
	}

	IMemory * lpcMemory = IMemory::init_get_instance();
	lpcMemory->memory_map_process_memory( nProcessId );
	vector<MemoryPage*> vlpcMemoryPages;
	vlpcMemoryPages = lpcMemory->memory_get_memory_pages();

	vector<ImageHeaderMemory*> vlpcModuleHeaders;
	lpcMemory->memory_get_module_headers( &vlpcModuleHeaders, nProcessId );

	MemoryPage * lpMemoryPage;
	ImageHeaderMemory * lpImageHeader;
	char * lpszModuleAssociation;
	for( int i = 0; i < (int)vlpcAddresses.size(); i++ ) {
		lpMemoryPage = IMemory::memory_find_memory_page_addr( 
			vlpcMemoryPages, vlpcAddresses[i]->get_address() );
		
		if( lpMemoryPage != NULL ) {
			lpImageHeader = IMemory::memory_find_memory_page_addr( 
				vlpcModuleHeaders, lpMemoryPage->get_allocation_baseaddress() );
			if( lpImageHeader != NULL ) {
				lpszModuleAssociation = lpImageHeader->get_image_name_ascii();
			}
			else {
				lpszModuleAssociation = "Executable but not associated with a module";
			}
		}
		else {
			lpszModuleAssociation = "Not associated with a memory page?";
		}

		printf( HEXPRINT " | %s | Contents:[", vlpcAddresses[i]->get_address(), 
			lpszModuleAssociation );

		unsigned char * lpucContents = (unsigned char *)
			vlpcAddresses[i]->get_address_contents_buffer();

		for( int j = 0; j < vlpcAddresses[i]->get_address_contents_size(); j++ ) {
			printf("%02X", lpucContents[j] );
		}

		printf( "]\n" );
	}
}