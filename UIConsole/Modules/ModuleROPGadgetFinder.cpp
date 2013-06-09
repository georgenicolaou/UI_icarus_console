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

#include "ModuleROPGadgetFinder.h"
#include <IProtections.h>
#include <IGadgetFinder.h>
#include "processor\IRegister.h"
#include "iDisasm\idisasm_include.h"
#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <string>
using namespace std;
void ExecuteROPGadgetFinder( PMODULEARGS lpModuleArgs );
void EnterMenu( vector<RopGadget *> * lpvRops, vector<RopGadget *> * lpvApis );

void * lpRopGadgetFinderArgs[2];

MODULEARGS arsModuleROPGadgetFinderArgs[] = {
	{
		"p",
		"The process ID of the process to analyze",
		TYPE_INT,
		FALSE,
		TRUE,
		&lpRopGadgetFinderArgs[0]
	},
	{
		"n",
		"Max number of instructions in gadget",
		TYPE_INT,
		FALSE,
		FALSE,
		&lpRopGadgetFinderArgs[1]
	},
	{
		"f0",
		"Filter out modules with DEP",
		TYPE_FLAG,
		FALSE,
		FALSE,
	},
	{
		"f2",
		"Filter out modules with SEH",
		TYPE_FLAG,
		FALSE,
		FALSE,
	},
	{
		"f3",
		"Find ROPS in ASLR modules",
		TYPE_FLAG,
		TRUE,
		FALSE
	},
	{
		"l",
		"Log outputs to file",
		TYPE_FLAG,
		FALSE,
		FALSE
	}
};

MODULE sModuleROPGadgetFinder = {
	"ROP Gadget Finder",
	"Parse and query ROP gadgets within a program's memory",
	"gadget_finder",
	"gf",
	MYARRAYSIZE( arsModuleROPGadgetFinderArgs ),
	(PMODULEARGS)&arsModuleROPGadgetFinderArgs,
	&ExecuteROPGadgetFinder
};

void ExecuteROPGadgetFinder( PMODULEARGS lpModuleArgs )
{
	IProtections::_PROTECTION_FILTER eProtectionFilter = 
		(IProtections::_PROTECTION_FILTER)NULL;

	if( (BOOL)(lpModuleArgs+2)->bSet ) {
		eProtectionFilter = (IProtections::_PROTECTION_FILTER)
			( eProtectionFilter | IProtections::PROTECTION_0 );
	}
	if( (BOOL)(lpModuleArgs+3)->bSet ) {
		eProtectionFilter = (IProtections::_PROTECTION_FILTER)
			( eProtectionFilter | IProtections::PROTECTION_2 );
	}
	if( (BOOL)(lpModuleArgs+4)->bSet ) {
		eProtectionFilter = (IProtections::_PROTECTION_FILTER)
			( eProtectionFilter | IProtections::PROTECTION_ASLR );
	}

	int nProcessId = (int)lpModuleArgs->lpArgument;
	
	BOOL bLog = (BOOL)(lpModuleArgs+5)->bSet;

	IGadgetFinder * lpGadgetFinder = IGadgetFinder::init_get_instance();
	IProtections * lpProtections = IProtections::init_get_instance();

	if( (BOOL)(lpModuleArgs+1)->bSet ) {
		int nMaxGadgetSize = (int)(lpModuleArgs+1)->lpArgument;
		lpGadgetFinder->set_maximum_rop_size( nMaxGadgetSize );
	}

	lpProtections->apply_protection_filter( eProtectionFilter );

	printf("Retrieving Standard ROP Gadgets\n");
	if( lpGadgetFinder->proc_find_rop_gadgets( lpProtections, nProcessId ) 
		== FALSE ) {
			printf( "Error retrieving gadgets\n" );
			return;
	}

	printf("Retrieving API Call Gadgets\n");
	if( lpGadgetFinder->proc_find_api_gadgets( lpProtections, nProcessId ) 
		== FALSE ) {
			printf( "Error retrieving API gadgets\n" );
			return;
	}

	vector<RopGadget *> * lpvRops = lpGadgetFinder->get_found_rop_gadgets();
	vector<RopGadget *> * lpvApis = lpGadgetFinder->get_found_api_gadgets();

	printf( "Finished!\n\tROP Gadgets: %d\n\tAPI Gadgets: %d\n", lpvRops->size(), 
		lpvApis->size() );

	
	EnterMenu( lpvRops, lpvApis );
	return;
}

int GetOption( char * lpPrintMenu, int nNoOfOptions )
{
	BOOL bOk = FALSE;
	int nAnswer = 0;
	while( bOk == FALSE ) {
		printf( lpPrintMenu );
		printf("Icarus>");
		scanf( "%d", &nAnswer );
		if( nAnswer <= 0 || nAnswer > nNoOfOptions ) {
			printf( "Invalid Option\n" );
		}
		else {
			bOk = TRUE;
		}
	}
	return nAnswer;
}

void PrintGadget( RopGadget * lpGadget )
{
	printf( 
		"Gadget: %#X\n"
			"\tCategories: ",
		lpGadget->get_gadget_address() );

	GADGET_CATEGORY eCategory = lpGadget->get_gadget_category();

	if( eCategory & GC_MEMORY ) printf( "MEMORY " );
	if( eCategory & GC_REGMEMORY ) printf( "REGMEMORY " );
	if( eCategory & GC_ASSIGNMENT ) printf( "ASSIGNMENT " );
	if( eCategory & GC_FUNCCALL ) printf( "FUNCCALL " );
	if( eCategory & GC_SYSCALL ) printf( "SYSCALL " );
	if( eCategory & GC_MATH ) printf( "MATH " );
	if( eCategory & GC_LOGICAL ) printf( "LOGICA " );
	if( eCategory & GC_CONTROLFLOW ) printf( "CONTROLFLOW " );
	if( eCategory & GC_SYSTEMINSTR ) printf( "SYSTEMINSTR " );
	if( eCategory & GC_UNKNOWNINSTR ) printf( "UNKNOWNINSTR " );

	printf( "\n\tType: " );

	GADGET_TYPE eType = lpGadget->get_gadget_type();
	if( eType & GT_CONTROLFLOW_REG ) printf( "CONTROLFLOW_REG " );
	if( eType & GT_CONTROLFLOW_MEM ) printf( "CONTROLFLOW_MEM " );
	if( eType & GT_CONTROLFLOW_REL ) printf( "CONTROLFLOW_REL " );
	if( eType & GT_ASSIGNS_ZERO ) printf( "ASSIGNS_ZERO " );
	if( eType & GT_STRING_MOVE ) printf( "STRING_MOVE " );
	if( eType & GT_STRING_CMP ) printf( "STRING_CMP " );

	printf( 
			"\n\tNumber Of Instructions: %d\n"
			"\tAffected Registers: ", 
			lpGadget->get_instructions()->size() );

	vector<IRegister *> * vAffectedRegs = lpGadget->get_affected_registers();

	if( vAffectedRegs->size() == 0 ) {
		printf( "NONE" );
	}
	for( int i = 0; i < (int)vAffectedRegs->size(); i++ ) {
		if( i + 1 == (int)vAffectedRegs->size() ) {
			printf( "%s", vAffectedRegs->at(i)->get_register_name() );
		}
		else {
			printf( "%s, ", vAffectedRegs->at(i)->get_register_name() );
		}
	}

	printf("\n\tRead Registers: " );
	vector<IRegister *> * vReadRegs = lpGadget->get_read_registers();
	if( vReadRegs->size() == 0 ) {
		printf( "NONE" );
	}
	for( int i = 0; i < (int)vReadRegs->size(); i++ ) {
		if( i + 1 == (int)vReadRegs->size() ) {
			printf( "%s", vReadRegs->at(i)->get_register_name() );
		}
		else {
			printf( "%s, ", vReadRegs->at(i)->get_register_name() );
		}
	}

	if( eCategory & GC_FUNCCALL ) {
		Function * lpFunction = lpGadget->get_function();
		printf( "\n\tFunction: %s [%#X]", lpFunction->get_function_name(), 
			lpFunction->get_function_virtual_address() );
	}
	printf("\n\tInstructions:\n");

	vector<PSIDISASM> * vInstructions = lpGadget->get_instructions();
	for( int i = 0; i < (int)vInstructions->size(); i++ ) {
		PSIDISASM lpDisasm = vInstructions->at(i);
		printf( "\t%s\n", lpDisasm->Mnemonic );
	}
}

void WriteOutputToFile( char * lpszFileName )
{
	freopen( lpszFileName, "wa", stdout );
}

void CloseOutput()
{
	fclose( stdout );
}

void HandleAPIGadgetsMenu( vector<RopGadget *> * lpvApis )
{
	int nAnswer = 0;
	string strInput;
	while( 1 ) {
		nAnswer = GetOption(
			"What would you like to do?\n"
			"\t[1] Print All\n"
			"\t[2] Search for function\n"
			"\t[3] Back to menu\n",
			3 );
		switch( nAnswer ) {
		case 1:
			if( lpvApis->size() == 0 ) {
				printf( "No API Gadgets available" );
			}
			else {
				for( int i = 0; i < (int)lpvApis->size(); i++ ) {
					PrintGadget( lpvApis->at(i) );
					if( i % 5 == 0 )
						system("PAUSE");
				}
			}
			break;
		case 2:
			printf("Function Name:");
			std::cin >> strInput;
			for( int i = 0; i < (int)lpvApis->size(); i++ ) {
				if( strInput.compare( 
					lpvApis->at(i)->get_function()->get_function_name() ) 
					== 0 ) {
						PrintGadget( lpvApis->at(i) );
				}
			}
			break;
		case 3:
			return;
		}
	}
}

typedef struct {
	char * lpFlagName;
	BOOL bEnabled;
} FLAGS;


FLAGS arsCategoryFlags[] = {
	{ "MEMORY" },
	{ "REGMEMORY" },
	{ "ASSIGNMENT" },
	{ "FUNCCALL" },
	{ "SYSCALL" },
	{ "MATH" },
	{ "LOGICAL" },
	{ "CONTROLFLOW" },
	{ "SYSTEMINSTR" },
};

FLAGS arsTypeFlags[] = {
	{ "CONTROLFLOW_REG" },
	{ "CONTROLFLOW_MEM" },
	{ "CONTROLFLOW_REL" },
	{ "ASSIGNS_ZERO" },
	{ "STRING_MOVE" },
	{ "STRING_CMP" },
};

FLAGS arsRegisters[] = {
	{ "ECX" },
	{ "EAX" },
	{ "EDX" },
	{ "EBX" },
	{ "ESP" },
	{ "EBP" },
	{ "ESI" },
	{ "EDI" },
	{ "EIP" },
};

void UnsetFlags( int nArrSize, FLAGS lpFlags[] )
{
	for( int i = 0; i < nArrSize; i++ ) {
		lpFlags[i].bEnabled = FALSE;
	}
}

void EnableDisableFlags( int nNumberOfFlags, FLAGS lpFlags[]  )
{
	int nAnswer = 0;
	int i = 0;
	while( 1 ) {
		printf("Enable/Disable:\n");
		for( i = 1; i <= nNumberOfFlags; i++ ) {
			printf( "\t[%d]", i );
			if( lpFlags[i].bEnabled ) {
				printf("\tDisable %s\n", lpFlags[i].lpFlagName );
			}
			else {
				printf("\tEnable %s\n", lpFlags[i].lpFlagName );
			}
		}
		printf( "\t[%d] Exit", i );
		printf("icarus>");
		scanf( "%d", &nAnswer );
		if( nAnswer <= 0 || nAnswer > i ) {
			printf( "Bad Answer\n" );
			system("PAUSE");
			continue;
		}
		if( nAnswer == i ) return;
		if( lpFlags[nAnswer].bEnabled ) {
			lpFlags[nAnswer].bEnabled = FALSE;
		}
		else {
			lpFlags[nAnswer].bEnabled = TRUE;
		}
	}
}

#define ARRAY_SIZE( arr ) sizeof( *arr ) / sizeof( arr )

void HandleGadgetSearch( vector<RopGadget *> * lpvRops )
{
	int nAnswer;
	BOOL bContinue = TRUE;
	GADGET_CATEGORY eCategory = GC_NONE;
	GADGET_TYPE eType = GT_NONE;
	vector<IRegister::_GENERAL_REGISTER_ENUM> vAffectedRegisters;
	vector<IRegister::_GENERAL_REGISTER_ENUM> vReadRegisters;

	while( bContinue ) {
		nAnswer = GetOption(
			"Select filter parameter:\n"
				"\t[1] Gadget Category\n"
				"\t[2] Gadget Type\n"
				"\t[3] Affected Registers\n"
				"\t[4] Read Registers\n"
				"\t[5] Execute Filter\n",
			5 );
		switch( nAnswer ) {
		case 1:
			EnableDisableFlags( ARRAY_SIZE( &arsCategoryFlags ), 
				(FLAGS *)&arsCategoryFlags );
			if( arsCategoryFlags[0].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_MEMORY);

			if( arsCategoryFlags[1].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_REGMEMORY);

			if( arsCategoryFlags[2].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_ASSIGNMENT);

			if( arsCategoryFlags[3].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_FUNCCALL);

			if( arsCategoryFlags[4].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_SYSCALL);

			if( arsCategoryFlags[5].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_MATH);

			if( arsCategoryFlags[6].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_LOGICAL);

			if( arsCategoryFlags[7].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_CONTROLFLOW);

			if( arsCategoryFlags[8].bEnabled )
				eCategory = (GADGET_CATEGORY)(eCategory | GC_SYSTEMINSTR);
			break;
		case 2:
			EnableDisableFlags( ARRAY_SIZE( arsTypeFlags ), arsTypeFlags );
			if( arsTypeFlags[0].bEnabled )
				eType = (GADGET_TYPE)(eType | GT_CONTROLFLOW_REG);
			if( arsTypeFlags[1].bEnabled )
				eType = (GADGET_TYPE)(eType | GT_CONTROLFLOW_MEM);
			if( arsTypeFlags[2].bEnabled )
				eType = (GADGET_TYPE)(eType | GT_CONTROLFLOW_REL);
			if( arsTypeFlags[3].bEnabled )
				eType = (GADGET_TYPE)(eType | GT_ASSIGNS_ZERO);
			if( arsTypeFlags[4].bEnabled )
				eType = (GADGET_TYPE)(eType | GT_STRING_MOVE);
			if( arsTypeFlags[5].bEnabled )
				eType = (GADGET_TYPE)(eType | GT_STRING_CMP);
			break;
		case 3:
			UnsetFlags( ARRAY_SIZE( arsRegisters ), arsRegisters );
			EnableDisableFlags( ARRAY_SIZE( arsRegisters ), arsRegisters );
			if( arsRegisters[0].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG0 );
			if( arsRegisters[1].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG1 );
			if( arsRegisters[2].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG2 );
			if( arsRegisters[3].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG3 );
			if( arsRegisters[4].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG_SP );
			if( arsRegisters[5].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG_FP );
			if( arsRegisters[6].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG6 );
			if( arsRegisters[7].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG7 );
			if( arsRegisters[8].bEnabled )
				vAffectedRegisters.push_back( IRegister::REG_PC );
			break;
		case 4:
			UnsetFlags( ARRAY_SIZE( arsRegisters ), arsRegisters );
			EnableDisableFlags( ARRAY_SIZE( arsRegisters ), arsRegisters );
			if( arsRegisters[0].bEnabled )
				vReadRegisters.push_back( IRegister::REG0 );
			if( arsRegisters[1].bEnabled )
				vReadRegisters.push_back( IRegister::REG1 );
			if( arsRegisters[2].bEnabled )
				vReadRegisters.push_back( IRegister::REG2 );
			if( arsRegisters[3].bEnabled )
				vReadRegisters.push_back( IRegister::REG3 );
			if( arsRegisters[4].bEnabled )
				vReadRegisters.push_back( IRegister::REG_SP );
			if( arsRegisters[5].bEnabled )
				vReadRegisters.push_back( IRegister::REG_FP );
			if( arsRegisters[6].bEnabled )
				vReadRegisters.push_back( IRegister::REG6 );
			if( arsRegisters[7].bEnabled )
				vReadRegisters.push_back( IRegister::REG7 );
			if( arsRegisters[8].bEnabled )
				vReadRegisters.push_back( IRegister::REG_PC );
			break;
		case 5:
			bContinue = FALSE;
			break;
		}
	}

	for( int i = 0; i < (int)lpvRops->size(); i++ ) {
		RopGadget * lpGadget = lpvRops->at(i);

		GADGET_CATEGORY eThisCategory = lpGadget->get_gadget_category();
		if( eThisCategory & eCategory != eCategory ) 
			continue;

		GADGET_TYPE eThisType = lpGadget->get_gadget_type();
		if( eThisType & eType != eType )
			continue;

		vector<IRegister *> * lpvTempRegs = lpGadget->get_affected_registers();

		BOOL bMeetsRegs;
		for( int j = 0; j < (int)vAffectedRegisters.size(); j++ ) {
			bMeetsRegs = FALSE;
			for( int k = 0; k < (int)lpvTempRegs->size(); k++ ) {
				if( lpvTempRegs->at(k)->get_register_type() == vAffectedRegisters[j] ) {
					bMeetsRegs = TRUE;
					break;
				}
			}
			if( bMeetsRegs == FALSE ) {
				break;
			}
		}
		if( bMeetsRegs == FALSE ) 
			continue; //Next gadget

		lpvTempRegs = lpGadget->get_read_registers();
		for( int j = 0; j < (int)vReadRegisters.size(); j++ ) {
			bMeetsRegs = FALSE;
			for( int k = 0; k < (int)lpvTempRegs->size(); k++ ) {
				if( lpvTempRegs->at(k)->get_register_type() == vReadRegisters[j] ) {
					bMeetsRegs = TRUE;
					break;
				}
			}
			if( bMeetsRegs == FALSE ) {
				break;
			}
		}
		if( bMeetsRegs == FALSE ) 
			continue; //Next gadget

		PrintGadget( lpGadget );
	}
}

void HandleStdRopGadgetsMenu( vector<RopGadget *> * lpvRops )
{
	BOOL bNested = TRUE;
	int nAnswer = 0;
	while( 1 ) {
		nAnswer = GetOption(
			"What would you like to do?\n"
			"\t[1] Print all gadgets\n"
			"\t[2] Search for gadgets\n"
			"\t[3] Return to menu\n", 
			3);

		switch( nAnswer ) {
		case 1:
			for( int i = 0; i < (int)lpvRops->size(); i++ ) {
				PrintGadget( lpvRops->at(i) );
				if( i % 5 == 0 ) {
					system("PAUSE");
				}
			}
			break;
		case 2:
			HandleGadgetSearch( lpvRops );
			break;
		case 3:
			return;
		}
	}
}

void EnterMenu( vector<RopGadget *> * lpvRops, vector<RopGadget *> * lpvApis )
{
	BOOL bExit = FALSE;
	BOOL bNested = FALSE;
	int nAnswer;
	while( !bExit ) {
		nAnswer = GetOption(
			"What gadgets would you like to view\n"
			"\t[1] Standard ROP Gadgets\n"
			"\t[2] API Gadgets\n",
			2 );
		switch( nAnswer ) {
		case 1: //Standard ROP Gadgets
			HandleStdRopGadgetsMenu( lpvRops );
			break;
		case 2: //API Gadgets
			HandleAPIGadgetsMenu( lpvApis );
			break;
		}
	}
}