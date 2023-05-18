// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using IntegrationTests.Common;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace IntegrationTests.Conformance.Basic;

public class ClientAuthenticationTests 
{
    private const string Category = "Conformance.Basic.ClientAuthenticationTests";

    private IdentityServerPipeline _pipeline = new IdentityServerPipeline();

    public ClientAuthenticationTests()
    {
        _pipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _pipeline.Clients.Add(new Client
        {
            Enabled = true,
            ClientId = "code_pipeline.Client",
            ClientSecrets = new List<Secret>
            {
                new Secret("secret".Sha512()),
                new Secret("1234567890123456"),
            },

            AllowedGrantTypes = GrantTypes.Code,
            AllowedScopes = { "openid" },

            RequireConsent = false,
            RequirePkce = false,
            RedirectUris = new List<string>
            {
                "https://code_pipeline.Client/callback",
                "https://code_pipeline.Client/callback?foo=bar&baz=quux"
            }
        });

        _pipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new Claim[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            }
        });

        _pipeline.OnConfigureIdentityServer += builder =>
        {
            builder.AddJwtBearerClientAuthentication();
        }; 
        
        _pipeline.Initialize();
    }

    [Fact]
    [Trait("Category", Category)]
    public async Task Token_endpoint_supports_client_authentication_with_basic_authentication_with_POST()
    {
        await _pipeline.LoginAsync("bob");

        var nonce = Guid.NewGuid().ToString();

        _pipeline.BrowserClient.AllowAutoRedirect = false;
        var url = _pipeline.CreateAuthorizeUrl(
            clientId: "code_pipeline.Client",
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_pipeline.Client/callback?foo=bar&baz=quux",
            nonce: nonce);
        var response = await _pipeline.BrowserClient.GetAsync(url);

        var authorization = _pipeline.ParseAuthorizationResponseUrl(response.Headers.Location.ToString());
        authorization.Code.Should().NotBeNull();

        var code = authorization.Code;

        // backchannel client
        var wrapper = new MessageHandlerWrapper(_pipeline.Handler);
        var tokenClient = new HttpClient(wrapper);
        var tokenResult = await tokenClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            ClientId = "code_pipeline.Client",
            ClientSecret = "secret",

            Code = code,
            RedirectUri = "https://code_pipeline.Client/callback?foo=bar&baz=quux"
        });

        tokenResult.IsError.Should().BeFalse();
        tokenResult.HttpErrorReason.Should().Be("OK");
        tokenResult.TokenType.Should().Be("Bearer");
        tokenResult.AccessToken.Should().NotBeNull();
        tokenResult.ExpiresIn.Should().BeGreaterThan(0);
        tokenResult.IdentityToken.Should().NotBeNull();

        wrapper.Response.Headers.CacheControl.NoCache.Should().BeTrue();
        wrapper.Response.Headers.CacheControl.NoStore.Should().BeTrue();
    }

    [Fact]
    [Trait("Category", Category)]
    public async Task Token_endpoint_supports_client_authentication_with_form_encoded_authentication_in_POST_body()
    {
        await _pipeline.LoginAsync("bob");

        var nonce = Guid.NewGuid().ToString();

        _pipeline.BrowserClient.AllowAutoRedirect = false;
        var url = _pipeline.CreateAuthorizeUrl(
            clientId: "code_pipeline.Client",
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_pipeline.Client/callback?foo=bar&baz=quux",
            nonce: nonce);
        var response = await _pipeline.BrowserClient.GetAsync(url);

        var authorization = _pipeline.ParseAuthorizationResponseUrl(response.Headers.Location.ToString());
        authorization.Code.Should().NotBeNull();

        var code = authorization.Code;

        // backchannel client
        var wrapper = new MessageHandlerWrapper(_pipeline.Handler);
        var tokenClient = new HttpClient(wrapper);
        var tokenResult = await tokenClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            ClientId = "code_pipeline.Client",
            ClientSecret = "secret",
            ClientCredentialStyle = ClientCredentialStyle.PostBody,

            Code = code,
            RedirectUri = "https://code_pipeline.Client/callback?foo=bar&baz=quux"
        });

        tokenResult.IsError.Should().BeFalse();
        tokenResult.HttpErrorReason.Should().Be("OK");
        tokenResult.TokenType.Should().Be("Bearer");
        tokenResult.AccessToken.Should().NotBeNull();
        tokenResult.ExpiresIn.Should().BeGreaterThan(0);
        tokenResult.IdentityToken.Should().NotBeNull();
    }
    
    [Fact]
    [Trait("Category", Category)]
    public async Task Token_endpoint_supports_client_authentication_with_client_secret_jwt_in_POST_body()
    {
        await _pipeline.LoginAsync("bob");

        var nonce = Guid.NewGuid().ToString();
        _pipeline.BrowserClient.AllowAutoRedirect = false;
        var url = _pipeline.CreateAuthorizeUrl(
            clientId: "code_pipeline.Client",
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_pipeline.Client/callback?foo=bar&baz=quux",
            nonce: nonce);
        var response = await _pipeline.BrowserClient.GetAsync(url);

        var authorization = _pipeline.ParseAuthorizationResponseUrl(response.Headers.Location.ToString());
        authorization.Code.Should().NotBeNull();

        var code = authorization.Code;

        // backchannel client
        var wrapper = new MessageHandlerWrapper(_pipeline.Handler);
        var tokenClient = new HttpClient(wrapper);
        var tokenResult = await tokenClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            ClientAssertion = new ClientAssertion
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = BuildAssertion(IdentityServerPipeline.BaseUrl.EnsureTrailingSlash(), "code_pipeline.Client", "1234567890123456")
            },
            Code = code,
            RedirectUri = "https://code_pipeline.Client/callback?foo=bar&baz=quux"
        });

        tokenResult.IsError.Should().BeFalse();
        tokenResult.HttpErrorReason.Should().Be("OK");
        tokenResult.TokenType.Should().Be("Bearer");
        tokenResult.AccessToken.Should().NotBeNull();
        tokenResult.ExpiresIn.Should().BeGreaterThan(0);
        tokenResult.IdentityToken.Should().NotBeNull();

        static string BuildAssertion(string authority, string clientId, string clientSecret)
        {
            var epochUtcNow = (DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / 10000000;
            const int expInSeconds = 10 * 60;
            var exp = (expInSeconds + epochUtcNow).ToString();

            var claims = new Claim[]
            {
                new Claim(JwtClaimTypes.JwtId, Guid.NewGuid().ToString()),
                new Claim(JwtClaimTypes.Issuer, clientId),
                new Claim(JwtClaimTypes.Subject, clientId),
                new Claim(JwtClaimTypes.Audience, authority),
                new Claim(JwtClaimTypes.Expiration, exp, ClaimValueTypes.Integer64),
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientSecret));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var header = new JwtHeader(signingCredentials);
            var payload = new JwtPayload(claims);
            var token = new JwtSecurityToken(header, payload);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}