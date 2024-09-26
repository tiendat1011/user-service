package dev.proj.userservice.service;

import dev.proj.userservice.dto.ClientRequest;
import dev.proj.userservice.dto.ResponseInfo;
import dev.proj.userservice.dto.UserResponse;
import dev.proj.userservice.model.Client;
import dev.proj.userservice.repository.ClientRepository;
import dev.proj.userservice.utils.ServerUtils;
import dev.proj.userservice.utils.UserUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository {
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    public ResponseInfo create(ClientRequest clientRequest) {
        Client client = clientFromRequest(clientRequest);
        clientRepository.save(client);
        return ResponseInfo.builder()
                .message(ServerUtils.CREATED_CLIENT_SUCCESS_MESSAGE)
                .statusCode(ServerUtils.CREATED_CLIENT_SUCCESS_CODE)
                .build();
    }

    private Client clientFromRequest(ClientRequest clientRequest) {
        return Client.builder()
                .clientId(clientRequest.getClientId())
                .clientSecret(clientRequest.getClientSecret())
                .authenticationMethods(clientRequest.getAuthenticationMethods())
                .authorizationGrantTypes(clientRequest.getAuthorizationGrantTypes())
                .redirectUris(clientRequest.getRedirectUris())
                .scopes(clientRequest.getScopes())
                .requireProofKey(clientRequest.isRequireProofKey())
                .build();
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findByClientId(id).orElseThrow(() -> new RuntimeException("Client not found"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId).orElseThrow(() -> new RuntimeException("Client not found"));
        return Client.toRegisteredClient(client);
    }
}
