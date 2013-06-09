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


#include "ModuleMemoryMap.h"
#include <vector>
#include "MemoryPage.h"
#include "ImageHeaderMemory.h"
#include "ThreadStack.h"
#include "IMemory.h"
#include "IProtections.h"



void ExecuteMemoryMap( PMODULEARGS lpModuleArgs );

void * lpMemoryMapArgs[1];

MODULEARGS asModuleMemoryMapArgs[] = {
	{
		"p",
		"Process ID of the process to map",
		TYPE_INT,
		FALSE,
		TRUE,
		&lpMemoryMapArgs[0]
	}
};

MODULE sModuleMemoryMap = {
	"Memory Mapper",
	"View the loaded modules, heaps and stacks of the specified process",
	"memory_mapper",
	"mm",
	1,
	(PMODULEARGS)&asModuleMemoryMapArgs,
	&ExecuteMemoryMap
};

void ExecuteMemoryMap( PMODULEARGS lpModuleArgs )
{
	int nProcessId = (int)lpModuleArgs->lpArgument;
	vector<MemoryPage*> * vlpcMemoryHeaps = new vector<MemoryPage*>;
	vector<ImageHeaderMemory*> vlpcModuleHeaders;
	vector<ThreadStack*> vlpcThreadStacks;
	vector<MemoryPage*> vlpcMemoryPages;
	IMemory * lpcMemory = IMemory::init_get_instance();

	IProtections * lpcProtections = IProtections::init_get_instance();
	lpcProtections->apply_protection_filter( IProtections::PROTECTION_ALL );

	if( lpcMemory->memory_map_process_memory( nProcessId ) == FALSE )
		return;
	lpcMemory->memory_get_proc_heaps( vlpcMemoryHeaps, nProcessId );
	lpcMemory->memory_get_module_headers( &vlpcModuleHeaders, nProcessId );
	lpcMemory->memory_get_proc_stacks( &vlpcThreadStacks, nProcessId, ALL_THREADS );

	vlpcMemoryPages = lpcMemory->memory_get_memory_pages();
	printf( "Address  |  Size    | AX |  Information\n");
	printf( "---------+----------+----+-------------\n");
	for( int i = 0; i < (int)vlpcMemoryPages.size(); i++ ) {
		printf( HEXPRINT " | " HEXPRINT " | ", 
			vlpcMemoryPages[i]->get_baseaddress(), 
			vlpcMemoryPages[i]->get_page_size() );

		( vlpcMemoryPages[i]->mem_read() ) ? printf("R") : printf(" ");
		( vlpcMemoryPages[i]->mem_write() ) ? printf("W") : printf(" ");
		( vlpcMemoryPages[i]->mem_execute() ) ? printf("E") : printf(" ");

		if( vlpcMemoryPages[i]->type_image() ) {
			for( int j = 0; j < (int)vlpcModuleHeaders.size(); j++ ) {
				if( vlpcMemoryPages[i]->get_allocation_baseaddress() != 
					vlpcModuleHeaders[j]->get_baseaddress() ) {
						continue;
				}
				lpcProtections->filter_module_allowed( vlpcModuleHeaders[j] );
				
				if( lpcProtections->is_protection_0() )
					printf( " | [%s]", lpcProtections->get_protection_0_name() );
				if( lpcProtections->is_protection_1() )
					printf( " | [%s]", lpcProtections->get_protection_1_name() );
				if( lpcProtections->is_protection_2() )
					printf( " | [%s]", lpcProtections->get_protection_2_name() );
				if( lpcProtections->is_protection_3() )
					printf( " | [%s]", lpcProtections->get_protection_3_name() );

				printf( " | %s ", vlpcModuleHeaders[j]->get_image_name_ascii() );
				break;
			}
		}
		else { //Check if heap or stack
			BOOL bFound = FALSE;
			for( int j = 0; j < (int)vlpcMemoryHeaps->size(); j++ ) {
				if( vlpcMemoryPages[i]->get_baseaddress() == 
					vlpcMemoryHeaps->at(j)->get_baseaddress() ) {
						printf( " HEAP " );
						bFound = TRUE;
						break;
				}
			}
			if( bFound == FALSE ) {
				for( int j = 0; j < (int)vlpcThreadStacks.size(); j++ ) {
					if( vlpcMemoryPages[i]->get_baseaddress() == 
						vlpcThreadStacks[j]->get_baseaddress() ) {
							printf( " Stack of Thread: 0x%X", 
								vlpcThreadStacks[j]->get_stack_thread_id() );
						break;
					}
				}
			}
		}
		printf( "\n" );
	}
	
}