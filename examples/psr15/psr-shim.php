<?php
declare(strict_types=1);

namespace Psr\Http\Message;

/**
 * Minimal PSR-7 style interfaces used by the demo.
 * These are NOT full implementations; they are only for demo purposes.
 */

interface MessageInterface {}
interface ResponseInterface extends MessageInterface {
    public function getStatusCode(): int;
    public function getReasonPhrase(): string;
    public function getHeaders(): array;
    public function hasHeader(string $name): bool;
    public function withHeader(string $name, string $value): self;
    public function getBody(): string;
    public function withBody(string $body): self;
}
interface ServerRequestInterface extends MessageInterface {
    public function getMethod(): string;
    public function getUri(): string;
    public function getQueryParams(): array;
    public function getParsedBody();
    public function getHeaders(): array;
    public function getCookieParams(): array;
    public function getBody(): string;
    public function getAttribute(string $name, mixed $default = null): mixed;
    public function withAttribute(string $name, mixed $value): self;
}

class Response implements ResponseInterface {
    private int $status = 200;
    private string $reason = 'OK';
    private array $headers = ['Content-Type' => ['text/html; charset=utf-8']];
    private string $body = '';

    public function __construct(int $status = 200, string $reason = 'OK', array $headers = [], string $body = '')
    {
        $this->status = $status;
        $this->reason = $reason;
        foreach ($headers as $k => $v) $this->headers[$k] = (array)$v;
        $this->body = $body;
    }
    public function getStatusCode(): int { return $this->status; }
    public function getReasonPhrase(): string { return $this->reason; }
    public function getHeaders(): array { return $this->headers; }
    public function hasHeader(string $name): bool { return isset($this->headers[$name]); }
    public function withHeader(string $name, string $value): self {
        $clone = clone $this; $clone->headers[$name] = [$value]; return $clone;
    }
    public function getBody(): string { return $this->body; }
    public function withBody(string $body): self { $clone = clone $this; $clone->body = $body; return $clone; }
}

class ServerRequest implements ServerRequestInterface {
    private string $method;
    private string $uri;
    private array $query;
    private array|string|null $parsedBody;
    private array $headers;
    private array $cookies;
    private string $rawBody;
    private array $attributes = [];

    public function __construct()
    {
        $this->method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $this->uri = $_SERVER['REQUEST_URI'] ?? '/';
        $this->query = $_GET ?? [];
        $this->cookies = $_COOKIE ?? [];
        $this->headers = function_exists('getallheaders') ? (getallheaders() ?: []) : [];
        $this->rawBody = file_get_contents('php://input') ?: '';
        if (($this->headers['Content-Type'] ?? '') === 'application/json') {
            $this->parsedBody = json_decode($this->rawBody, true);
        } else {
            $this->parsedBody = $_POST ?: null;
        }
    }

    public function getMethod(): string { return $this->method; }
    public function getUri(): string { return $this->uri; }
    public function getQueryParams(): array { return $this->query; }
    public function getParsedBody() { return $this->parsedBody; }
    public function getHeaders(): array { return $this->headers; }
    public function getCookieParams(): array { return $this->cookies; }
    public function getBody(): string { return $this->rawBody; }
    public function getAttribute(string $name, mixed $default = null): mixed { return $this->attributes[$name] ?? $default; }
    public function withAttribute(string $name, mixed $value): self { $clone = clone $this; $clone->attributes[$name] = $value; return $clone; }
}
