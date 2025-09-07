<?php
declare(strict_types=1);

namespace Demo\Runner;

use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\Response;

/**
 * A tiny middleware pipeline to chain PSR-15 middleware.
 */
final class Pipeline implements RequestHandlerInterface
{
    /** @var list<MiddlewareInterface> */
    private array $stack = [];
    private RequestHandlerInterface $finalHandler;

    public function __construct(RequestHandlerInterface $finalHandler)
    {
        $this->finalHandler = $finalHandler;
    }

    /** @param MiddlewareInterface $mw */
    public function pipe(MiddlewareInterface $mw): void
    {
        $this->stack[] = $mw;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if (empty($this->stack)) {
            return $this->finalHandler->handle($request);
        }
        $mw = array_shift($this->stack);
        return $mw->process($request, $this);
    }
}

final class FinalHandler implements RequestHandlerInterface
{
    /** @var callable */
    private $callback;

    public function __construct(callable $callback)
    {
        $this->callback = $callback;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $html = ($this->callback)($request);
        return (new Response())->withBody((string)$html);
    }
}
