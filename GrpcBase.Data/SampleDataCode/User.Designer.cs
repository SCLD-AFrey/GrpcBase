﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------
using System;
using DevExpress.Xpo;
using DevExpress.Xpo.Metadata;
using DevExpress.Data.Filtering;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;
namespace GrpcBase.Data
{

    public partial class User : XPObject
    {
        string fUserName;
        public string UserName
        {
            get { return fUserName; }
            set { SetPropertyValue<string>(nameof(UserName), ref fUserName, value); }
        }
        [Association(@"RoleReferencesUser")]
        public XPCollection<Role> Roles { get { return GetCollection<Role>(nameof(Roles)); } }
    }

}
