using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using static System.Console;

namespace explicacao
{
    internal class Program
    {
        static void Main(string[] args)
        {
            WindowsIdentity identity = ExibeInfoIdentity();
            WindowsPrincipal principal = ExibeInfoPrincipal(identity);
            ExibeInfoClaims(principal.Claims);
            ReadLine();
        }
        public static WindowsIdentity ExibeInfoIdentity()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity == null)
            {
                WriteLine("Não é um Windows Identity");
                return null;
            }
            WriteLine($"Tipo de Identity : {identity}");
            //Imprime o nome completo do tipo de objeto (classe).
            WriteLine($"Nome : {identity.Name}");
            //Acessa a propriedde Name do objeto Identity.
            WriteLine($"Autenticado : {identity.IsAuthenticated}");
            //Verifica se a identidade foi autenticada pelo sistema, imprime True, caso for verdadeiro ou False, caso for falso.
            WriteLine($"Tipo de Autenticação : {identity.AuthenticationType}");
            //Acessa a propriedade AuthenticationType, que indica o método usado para autenticação do usuário.
            WriteLine($"É usuário Anônimo ? : {identity.IsAnonymous}");
            //Verifica se o usuário é anônimo, imprime True caso for verdadeiro ou False, caso for falso.
            WriteLine($"Token de acesso : " + $"{identity.AccessToken.DangerousGetHandle()}");
            //Mostra o handle (ponteiro) do token de segurança.
            WriteLine();
            return identity;
        }
        public static WindowsPrincipal ExibeInfoPrincipal(WindowsIdentity identity)
        {
            WriteLine("Informação do Principal");
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            //Imprime um cabeçalho no console escrito "Informação do Principal"
            if (principal == null)
            {
                WriteLine("Não é um Windows Principal");
                return null;
            }
            WriteLine($"É Usuário ? {principal.IsInRole(WindowsBuiltInRole.User)}");
            //Verifica se o usuário pertence ao grupo "User".
            WriteLine($"É Administrador ? {principal.IsInRole(WindowsBuiltInRole.Administrator)}");
            //Verifica se o usuário é administrador.
            WriteLine();
            return principal;
        }
        public static void ExibeInfoClaims(IEnumerable<Claim> claims)
        {
            WriteLine("Declarações (Claims) ");
            foreach (var claim in claims)
            {
                WriteLine($"Assunto : {claim.Subject}");
                WriteLine($"Emissor : {claim.Issuer}");
                WriteLine($"Tipo : {claim.Type}");
                WriteLine($"Valor do Tipo : {claim.ValueType}");
                WriteLine($"Valor : {claim.Value}");
                foreach (var prop in claim.Properties)
                {
                    WriteLine($"\tProperty: {prop.Key} {prop.Value}");
                }
                WriteLine();
            }
        }
    }
}
